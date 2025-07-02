export interface ListDataDto<Result> {
  results: Result[];
  pagination?: {
    totalCount?: number;
    page: number;
    perPage: number;
  };
  filters?: {
    searchString?: string;
    [key: string]: any;
  };
  order?: {
    orderBy: string;
    orderDir: 'ASC' | 'DESC';
  };
  notes?: string;
}

export interface DeleteRecordDto<RecordType> {
  record: RecordType;
  isDeleted: boolean;
}
