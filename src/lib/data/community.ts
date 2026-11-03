/**
 * Where the CoreOps community lives.
 *
 * CoreOps has no Discord of its own, so both entries point at the repository.
 * The upstream Discord helper scripts are kept for compatibility, but these
 * constants are deliberately fixed at build time rather than fetched at run
 * time: a link baked into a shipped binary must not be one that can expire.
 *
 * This is deliberately a constant rather than something fetched at runtime.
 * Minting an invite needs a bot token, and a token inside a desktop binary is
 * a token handed to everyone who downloads it.
 */

export const COMMUNITY = {
	/** CoreOps has no chat server of its own; the repository is the community. */
	discordInvite: 'https://github.com/Daniel-King-8/CoreOps',
	/** Shown in the UI instead of the raw URL. */
	discordLabel: 'github.com/Daniel-King-8/CoreOps',
	/** The repository, where issues are filed and releases are published. */
	sponsorUrl: 'https://github.com/Daniel-King-8/CoreOps',
	sponsorLabel: 'github.com/Daniel-King-8/CoreOps'
} as const;
