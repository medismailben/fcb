"""
Test Fast Conditional Breakpoints.
"""

from __future__ import print_function

import os
import time
import re
import lldb
from lldbsuite.test.decorators import *
from lldbsuite.test.lldbtest import *
from lldbsuite.test import lldbutil


class FastConditionalBreakpoitsTestCase(TestBase):

    mydir = TestBase.compute_mydir(__file__)

    def setUp(self):
        # Call super's setUp().
        TestBase.setUp(self)
        self.file = lldb.SBFileSpec("main.c")
        self.comment = "Find the line number of condition breakpoint for local_count"
        self.condition = '"local_count == 9"'
        self.extra_options = "-c " + self.condition + " -I"
        self.binary = "a.out"

    @skipIfWindows
    def test_fast_conditional_breakpoint_flag_interpreter(self):
        """Enable fast conditional breakpoints with 'breakpoint modify -c <expr> id -I'."""
        self.build()
        self.enable_fast_conditional_breakpoint(use_interpreter=True)

    @skipIfWindows
    @add_test_categories(["pyapi"])
    def test_fast_conditional_breakpoint_flag_api(self):
        """Exercise fast conditional breakpoints with SB API"""
        self.build()
        self.enable_fast_conditional_breakpoint(use_interpreter=False)

    def enable_fast_conditional_breakpoint(self, use_interpreter):
        exe = self.getBuildArtifact(self.binary)
        self.target = self.dbg.CreateTarget(exe)
        self.assertTrue(self.target, VALID_TARGET)

        if use_interpreter:
            lldbutil.run_break_set_by_source_regexp(
                self, self.comment, self.extra_options
            )

            self.runCmd("breakpoint modify " + self.condition + " 1")

            self.expect("breakpoint list -f", substrs=["(FAST)"])
        else:
            # Now create a breakpoint on main.c by source regex'.
            breakpoint = self.target.BreakpointCreateBySourceRegex(
                self.comment, self.file
            )
            self.assertTrue(
                breakpoint and breakpoint.GetNumLocations() == 1,
                VALID_BREAKPOINT)

            # We didn't associate a thread index with the breakpoint, so it should
            # be invalid.
            self.assertTrue(
                breakpoint.GetThreadIndex() == lldb.UINT32_MAX,
                "the thread index should be invalid",
            )
            # The thread name should be invalid, too.
            self.assertTrue(
                breakpoint.GetThreadName() is None,
                "the thread name should be invalid")

            # Let's set the thread index for this breakpoint and verify that it is,
            # indeed, being set correctly and there's only one thread for the process.
            breakpoint.SetThreadIndex(1)
            self.assertTrue(
                breakpoint.GetThreadIndex() == 1,
                "the thread index has been set correctly",
            )

            # Get the breakpoint location from breakpoint after we verified that,
            # indeed, it has one location.
            location = breakpoint.GetLocationAtIndex(0)
            self.assertTrue(
                location and location.IsEnabled(), VALID_BREAKPOINT_LOCATION
            )

            # Set the condition on the breakpoint.
            location.SetCondition(self.condition)
            self.expect(
                location.GetCondition(),
                exe=False,
                startstr=self.condition)

            # Set condition on the breakpoint to be injected in-process.
            location.SetInjectCondition(True)
            self.assertTrue(
                location.GetInjectCondition(),
                VALID_BREAKPOINT_LOCATION)
