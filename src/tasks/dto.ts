import { IsEnum, IsOptional, IsString, IsDateString } from 'class-validator';

export class CreateTaskDto {
    @IsString()
    title: string;

    @IsOptional()
    description?: string; 

    @IsEnum(['LOW', 'MEDIUM', 'HIGH'])
    @IsOptional()
    priority?: 'LOW' | 'MEDIUM' | 'HIGH';

    @IsDateString()
    @IsOptional()
    dueDate?: Date;

}

export class UpdateTaskDto extends CreateTaskDto {
    @IsEnum(['PENDING', 'COMPLETED', 'IN_PROGRESS'])
    @IsOptional()
    status?: 'PENDING' | 'COMPLETED' | 'IN_PROGRESS';
}