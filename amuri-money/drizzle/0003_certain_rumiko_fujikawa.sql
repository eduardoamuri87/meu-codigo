ALTER TABLE `transactions` ADD `parent_id` text REFERENCES transactions(id);--> statement-breakpoint
ALTER TABLE `transactions` ADD `is_parent` integer DEFAULT false NOT NULL;--> statement-breakpoint
CREATE INDEX `idx_transactions_parent` ON `transactions` (`parent_id`);