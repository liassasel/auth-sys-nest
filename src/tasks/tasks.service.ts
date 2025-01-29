import { Injectable, ForbiddenException } from "@nestjs/common";
import { PrismaService } from "src/prisma.service";
import { CreateTaskDto, UpdateTaskDto } from "./dto";
import { Role } from "src/auth/types/role.enum";
import { NotFoundException } from "@nestjs/common";


@Injectable()
export class TasksService {
    constructor(private prisma: PrismaService) {}

    //Create Task (Only Autgenticated Users)

    async createTask(userId: number, dto: CreateTaskDto) {
        return this.prisma.task.create({
            data: {
                title: dto.title,
                description: dto.description,
                priority: dto.priority,
                dueDate: dto.dueDate,
                userId
            },
        });
    }

    // tasks with filters and paginations 

    async getTasks(userId: number, role: Role, filters?: any) {
        const whereClause: any = role === 'ADMIN' ? {} : { userId };
        
        if (filters?.status) whereClause.status = filters.status;
        if (filters?.priority) whereClause.priority = filters.priority;
        if (filters?.dueDate) whereClause.dueDate = { lte: new Date(filters.dueDate) };
    
        return this.prisma.task.findMany({ where: whereClause });
    }
    

    // Update task

    async updateTask(userId: number, role: Role, taskId: number, dto: UpdateTaskDto) {
        const task = await this.prisma.task.findUnique({ where: { id: taskId } });
        
        if (!task) throw new NotFoundException('Task not found');
        if (task.userId !== userId && role !== 'ADMIN') {
            throw new ForbiddenException('Permission denied');
        }
    
        return this.prisma.task.update({
            where: { id: taskId },
            data: dto
        });
    }

    async deleteTask(userId: number, role: Role, taskId: number) {
        const task = await this.prisma.task.findUnique({ where: {id: taskId} });

    if (task.userId !== userId && role !== 'ADMIN') {
        throw new ForbiddenException('You not have permission to delete this task');
    }

    return this.prisma.task.delete({ where: {id: taskId} });
    }
}