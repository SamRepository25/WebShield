export function getScoreColorClass(score: number): string {
  if (score >= 90) return 'text-success';
  if (score >= 70) return 'text-primary';
  if (score >= 50) return 'text-warning';
  if (score >= 30) return 'text-warning';
  return 'text-destructive';
}

export function getGradeColorClass(grade: string): string {
  if (grade === 'A') return 'text-success';
  if (grade === 'B') return 'text-primary';
  if (grade === 'C') return 'text-warning';
  if (grade === 'D' || grade === 'E') return 'text-warning';
  return 'text-destructive';
}
