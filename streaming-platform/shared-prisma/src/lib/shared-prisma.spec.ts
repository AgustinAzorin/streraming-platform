import { sharedPrisma } from './shared-prisma';

describe('sharedPrisma', () => {
  it('should work', () => {
    expect(sharedPrisma()).toEqual('shared-prisma');
  });
});
