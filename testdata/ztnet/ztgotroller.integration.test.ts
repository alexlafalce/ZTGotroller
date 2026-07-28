jest.mock("~/server/db", () => ({
	prisma: {
		user: {
			findFirst: jest.fn().mockResolvedValue({
				options: {
					ztCentralApiKey: null,
					ztCentralApiUrl: null,
					localControllerSecret: process.env.ZT_SECRET,
					localControllerUrl: process.env.ZT_ADDR,
				},
			}),
		},
	},
}));

import {
	get_controller_networks,
	get_controller_status,
	get_controller_version,
	get_network,
	member_delete,
	member_details,
	member_update,
	network_create,
	network_delete,
	network_members,
	network_update,
	peers,
} from "../ztApi";

const ctx = {
	session: { user: { id: "ztgotroller-integration" } },
} as never;

test("current ZTNet local-controller lifecycle works against ZTGotroller", async () => {
	const status = await get_controller_status(ctx, false);
	expect(status.address).toMatch(/^[0-9a-f]{10}$/);
	await expect(get_controller_version({ ctx })).resolves.toBeDefined();

	const created = await network_create(
		ctx,
		"ZTNet integration",
		{
			v4AssignMode: { zt: true },
			ipAssignmentPools: [{ ipRangeStart: "10.77.0.10", ipRangeEnd: "10.77.0.20" }],
			routes: [{ target: "10.77.0.0/24", via: null }],
			rules: [{ type: "ACTION_ACCEPT" }],
		},
		false,
	);
	const nwid = created.nwid;
	expect(nwid).toMatch(/^[0-9a-f]{16}$/);
	await expect(get_controller_networks(ctx, false)).resolves.toContain(nwid);
	await expect(get_network(ctx, nwid, false)).resolves.toMatchObject({
		nwid,
		name: "ZTNet integration",
	});

	await expect(
		network_update({
			ctx,
			nwid,
			updateParams: { name: "ZTNet updated" },
		}),
	).resolves.toMatchObject({ name: "ZTNet updated" });

	const memberId = "abcdef1234";
	await expect(
		member_update({
			ctx,
			nwid,
			memberId,
			updateParams: { authorized: true, name: "external member" },
		}),
	).resolves.toMatchObject({ id: memberId, address: memberId, authorized: true });
	const listedMembers = await network_members(ctx, nwid, false);
	expect(Object.keys(listedMembers)).toContain(memberId);
	await expect(member_details(ctx, nwid, memberId, false)).resolves.toMatchObject({
		id: memberId,
		name: "external member",
	});
	await expect(peers(ctx)).resolves.toEqual(expect.any(Array));

	await expect(member_delete({ ctx, nwid, memberId, central: false })).resolves.toBe(200);
	await expect(network_delete(ctx, nwid, false)).resolves.toMatchObject({ status: 200 });
});
