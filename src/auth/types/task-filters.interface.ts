import { Priority } from './priority.enum';
import { Status } from './status.enum';

export interface TaskFilters{
    status?: Status,
    priority?: Priority,
    dueDate?: Date;
}