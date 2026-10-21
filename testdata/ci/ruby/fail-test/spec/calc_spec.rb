# frozen_string_literal: true

RSpec.describe Calc do
  it 'adds two numbers' do
    expect(described_class.add(2, 2)).to eq(5)
  end
end
