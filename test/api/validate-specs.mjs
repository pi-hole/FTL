// Pi-hole: A black hole for Internet advertisements
// (c) 2021 Pi-hole, LLC (https://pi-hole.net)
// Network-wide ad blocking via your own hardware.
//
// FTL - API test file
//
// This is a node script
//
// This file is copyright under the latest version of the EUPL.
// Please see LICENSE file for your rights under this license.

import { Validator } from "@seriousme/openapi-schema-validator";
import fs from "fs/promises";

const validator = new Validator();

const specs = await fs.readdir("src/api/docs/content/specs/");

specs
  .filter((spec) => spec !== "main.yaml")
  .forEach((spec) =>
    validator.addSpecRef(`src/api/docs/content/specs/${spec}`, spec)
  );

await validator.validate("src/api/docs/content/specs/main.yaml");
