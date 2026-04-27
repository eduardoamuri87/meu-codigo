CREATE TABLE `cost_centers` (
	`id` text PRIMARY KEY NOT NULL,
	`name` text NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
ALTER TABLE `recurrences` ADD `cost_center_id` text REFERENCES cost_centers(id);--> statement-breakpoint
ALTER TABLE `transactions` ADD `cost_center_id` text REFERENCES cost_centers(id);
