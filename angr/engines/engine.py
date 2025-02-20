from __future__ import annotations

from typing import Generic, TypeVar
import abc
import logging

import claripy
from archinfo.arch_soot import SootAddressDescriptor

import angr
from angr.sim_state import SimState
from angr import sim_options as o
from angr.errors import SimException
from angr.state_plugins.inspect import BP_AFTER, BP_BEFORE
from .successors import SimSuccessors


l = logging.getLogger(name=__name__)


StateType = TypeVar("StateType")
ResultType = TypeVar("ResultType")
DataType_co = TypeVar("DataType_co", covariant=True)
HeavyState = SimState[int | SootAddressDescriptor, claripy.ast.BV | SootAddressDescriptor]


class SimEngineBase(Generic[StateType]):
    """
    Even more basey of a base class for SimEngine. Used as a base by mixins which want access to the project but for
    which having method `process` (contained in `SimEngine`) doesn't make sense
    """

    state: StateType

    def __init__(self, project: angr.Project, **kwargs):
        if kwargs:
            raise TypeError("Unused initializer args: " + ", ".join(kwargs.keys()))
        self.project = project
        self.arch = self.project.arch

    def __getstate__(self):
        return (self.project,)

    def __setstate__(self, state):
        self.project = state[0]


class SimEngine(Generic[StateType, ResultType], SimEngineBase[StateType], metaclass=abc.ABCMeta):
    """
    A SimEngine is a class which understands how to perform execution on a state. This is a base class.
    """

    @abc.abstractmethod
    def process(self, state: StateType, **kwargs) -> ResultType:
        """
        The main entry point for an engine. Should take a state and return a result.

        :param state:   The state to proceed from
        :return:        The result. Whatever you want ;)
        """


class SuccessorsMixin(SimEngine[HeavyState, SimSuccessors]):
    """
    A mixin for SimEngine which implements ``process`` to perform common operations related to symbolic execution
    and dispatches to a ``process_successors`` method to fill a SimSuccessors object with the results.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.successors: SimSuccessors | None = None

    def process(self, state: HeavyState, **kwargs) -> SimSuccessors:  # pylint:disable=unused-argument
        """
        Perform execution with a state.

        You should only override this method in a subclass in order to provide the correct method signature and
        docstring. You should override the ``_process`` method to do your actual execution.

        :param state:       The state with which to execute. This state will be copied before
                            modification.
        :param inline:      This is an inline execution. Do not bother copying the state.
        :param force_addr:  Force execution to pretend that we're working at this concrete address
        :returns:           A SimSuccessors object categorizing the execution's successor states
        """
        inline = kwargs.pop("inline", False)
        force_addr = kwargs.pop("force_addr", None)

        ip = state._ip
        addr = (
            (ip if isinstance(ip, SootAddressDescriptor) else state.solver.eval(ip))
            if force_addr is None
            else force_addr
        )

        # make a copy of the initial state for actual processing, if needed
        new_state = state.copy() if not inline and o.COPY_STATES in state.options else state
        # enforce this distinction
        old_state = state
        del state
        self.state = new_state

        # we have now officially begun the stepping process! now is where we "cycle" a state's
        # data - move the "present" into the "past" by pushing an entry on the history stack.
        # nuance: make sure to copy from the PREVIOUS state to the CURRENT one
        # to avoid creating a dead link in the history, messing up the statehierarchy
        new_state.register_plugin("history", old_state.history.make_child())
        new_state.history.recent_bbl_addrs.append(addr)
        if new_state.arch.unicorn_support:
            assert isinstance(addr, int)
            new_state.scratch.executed_pages_set = {addr & ~0xFFF}

        self.successors = SimSuccessors(addr, old_state)

        new_state._inspect(
            "engine_process", when=BP_BEFORE, sim_engine=self, sim_successors=self.successors, address=addr
        )
        self.successors = new_state._inspect_getattr("sim_successors", self.successors)
        try:
            self.process_successors(self.successors, **kwargs)
        except SimException as e:
            if o.EXCEPTION_HANDLING not in old_state.options:
                raise
            assert old_state.project is not None
            old_state.project.simos.handle_exception(self.successors, self, e)

        new_state._inspect("engine_process", when=BP_AFTER, sim_successors=self.successors, address=addr)
        self.successors = new_state._inspect_getattr("sim_successors", self.successors)
        assert self.successors is not None

        # downsizing
        if new_state.supports_inspect:
            new_state.inspect.downsize()
        # if not TRACK, clear actions on OLD state
        # if o.TRACK_ACTION_HISTORY not in old_state.options:
        #    old_state.history.recent_events = []

        # fix up the descriptions...
        description = str(self.successors)
        l.info("Ticked state: %s", description)
        for succ in self.successors.all_successors:
            succ.history.recent_description = description
        for succ in self.successors.flat_successors:
            succ.history.recent_description = description

        return self.successors

    def process_successors(self, successors, **kwargs):  # pylint:disable=unused-argument,no-self-use
        """
        Implement this function to fill out the SimSuccessors object with the results of stepping state.

        In order to implement a model where multiple mixins can potentially handle a request, a mixin may implement
        this method and then perform a super() call if it wants to pass on handling to the next mixin.

        Keep in mind python's method resolution order when composing multiple classes implementing this method.
        In short: left-to-right, depth-first, but deferring any base classes which are shared by multiple subclasses
        (the merge point of a diamond pattern in the inheritance graph) until the last point where they would be
        encountered in this depth-first search. For example, if you have classes A, B(A), C(B), D(A), E(C, D), then the
        method resolution order will be E, C, B, D, A.

        :param state:           The state to manipulate
        :param successors:      The successors object to fill out
        :param kwargs:          Any extra arguments. Do not fail if you are passed unexpected arguments.
        """
        successors.processed = False  # mark failure
