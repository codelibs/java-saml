package org.codelibs.saml2.core.model;

import java.util.List;

public class SubjectConfirmationIssue {
    private final int subjectConfirmationIndex;
    private final String message;

    public SubjectConfirmationIssue(final int subjectConfirmationIndex, final String message) {
        this.subjectConfirmationIndex = subjectConfirmationIndex;
        this.message = message;
    }

    public static String prettyPrintIssues(final List<SubjectConfirmationIssue> subjectConfirmationDataIssues) {
        final StringBuilder subjectConfirmationDataIssuesMsg =
                new StringBuilder("A valid SubjectConfirmation was not found on this Response");
        if (subjectConfirmationDataIssues.size() > 0) {
            subjectConfirmationDataIssuesMsg.append(": ");
        }
        for (int i = 0; i < subjectConfirmationDataIssues.size(); i++) {
            final SubjectConfirmationIssue issue = subjectConfirmationDataIssues.get(i);
            if (subjectConfirmationDataIssues.size() > 1) {
                subjectConfirmationDataIssuesMsg.append("\n[").append(issue.subjectConfirmationIndex).append("] ");
            }
            subjectConfirmationDataIssuesMsg.append(issue.message);
            if (i != subjectConfirmationDataIssues.size() - 1) {
                subjectConfirmationDataIssuesMsg.append(", ");
            }
        }

        return subjectConfirmationDataIssuesMsg.toString();
    }
}