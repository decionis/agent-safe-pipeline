/**
 * The adopter's process, in full: the executor from the package, the
 * handlers from this directory, the configuration from the environment and
 * mounted files. A missing or invalid value is a refusal to start that names
 * the variable and never its value.
 */
import { serve } from "@decionis/agentsafe";
import { handlers } from "./Handlers.js";

await serve(handlers);
