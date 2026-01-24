# CustomWordPositionOccurenceResponse

A Word Position Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**iPage** | **number** | The page where the word occurence was found | [optional] [default to undefined]
**iX** | **number** | The X coordinate (Horizontal) where the Word occurence was found.  Coordinate is calculated at 100dpi (dot per inch). | [optional] [default to undefined]
**iY** | **number** | The Y coordinate (Vertical) where the Word occurence was found.  Coordinate is calculated at 100dpi (dot per inch). | [optional] [default to undefined]

## Example

```typescript
import { CustomWordPositionOccurenceResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomWordPositionOccurenceResponse = {
    iPage,
    iX,
    iY,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
