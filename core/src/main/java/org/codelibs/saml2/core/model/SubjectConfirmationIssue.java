package org.codelibs.saml2.core.model;

import java.util.List;

/**
 * Represents a validation issue found on a SubjectConfirmation element of a SAML Response.
 */
public class SubjectConfirmationIssue {
    private final int subjectConfirmationIndex;
    private final String message;

    /**
     * Constructor.
     *
     * @param subjectConfirmationIndex the index of the SubjectConfirmation element with the issue
     * @param message                  the message describing the issue
     */
    public SubjectConfirmationIssue(final int subjectConfirmationIndex, final String message) {
        this.subjectConfirmationIndex = subjectConfirmationIndex;
        this.message = message;
    }

    /**
     * Builds a human-readable message describing the given SubjectConfirmation issues.
     *
     * @param subjectConfirmationDataIssues the list of issues to describe
     * @return a formatted message describing the issues
     */
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