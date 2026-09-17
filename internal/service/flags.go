package service

// Flags are named, mechanical signals. The server states facts and leaves the
// reading to the caller: a sentence produced here would be repeated as an
// instance-backed finding, with the rule that generated it nowhere in sight.
//
// Each flag's exact condition is documented in the README.
const (
	FlagWarninglisted         = "warninglisted"
	FlagWarninglistedAndToIDs = "warninglisted_and_to_ids"
	FlagCoveragePartial       = "warninglist_coverage_partial"
	FlagCheckUnavailable      = "warninglist_check_unavailable"
	FlagResultsTruncated      = "results_truncated"
)

func coverageFlags(rep Report) []string {
	switch rep.Coverage {
	case CoveragePartial:
		return []string{FlagCoveragePartial}
	case CoverageUnavailable:
		return []string{FlagCheckUnavailable}
	}
	return nil
}
