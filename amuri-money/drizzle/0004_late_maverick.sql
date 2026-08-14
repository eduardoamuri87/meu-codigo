CREATE TABLE `month_snapshots` (
	`id` text PRIMARY KEY NOT NULL,
	`year` integer NOT NULL,
	`month` integer NOT NULL,
	`gateway_delta` real NOT NULL,
	`computed_at` integer NOT NULL
);
