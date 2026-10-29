import { Request, Response } from 'express';

interface Filter { field: string; value: string }

export class ReportService {
  constructor(private readonly db: any) {}

  async byField(filter: Filter): Promise<any[]> {
    const sql = `SELECT * FROM reports WHERE ${filter.field} = '${filter.value}'`;
    return this.db.query(sql);
  }

  async byId(id: number): Promise<any[]> {
    return this.db.query('SELECT * FROM reports WHERE id = $1', [id]);
  }
}

export const handler = async (req: Request, res: Response) => {
  const rows = await knex.raw(`SELECT * FROM reports WHERE owner = '${req.query.owner}'`);
  res.json(rows);
};
