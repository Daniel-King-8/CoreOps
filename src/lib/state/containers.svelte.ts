/**
 * The Containers workspace's shared state: actions in flight, so Settings
 * waits for them before switching the tool off.
 */

let inFlight = $state(0);

/** Something is changing on a host right now (Compose up, a removal). */
export function isBusy(): boolean {
	return inFlight > 0;
}

/** Run `work` counted as in flight. */
export async function busy<T>(work: () => Promise<T>): Promise<T> {
	inFlight += 1;
	try {
		return await work();
	} finally {
		inFlight -= 1;
	}
}
