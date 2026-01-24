# EzsignannotationResponseCompound

A Ezsignannotation Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsignannotationID** | **number** | The unique ID of the Ezsignannotation | [default to undefined]
**fkiEzsigndocumentID** | **number** | The unique ID of the Ezsigndocument | [default to undefined]
**eEzsignannotationHorizontalalignment** | [**EnumHorizontalalignment**](EnumHorizontalalignment.md) |  | [optional] [default to undefined]
**eEzsignannotationVerticalalignment** | [**EnumVerticalalignment**](EnumVerticalalignment.md) |  | [optional] [default to undefined]
**eEzsignannotationType** | [**FieldEEzsignannotationType**](FieldEEzsignannotationType.md) |  | [default to undefined]
**iEzsignannotationX** | **number** | The X coordinate (Horizontal) where to put the Ezsignannotation on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsignannotation 2 inches from the left border of the page, you would use \&quot;200\&quot; for the X coordinate. | [default to undefined]
**iEzsignannotationY** | **number** | The Y coordinate (Vertical) where to put the Ezsignannotation on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsignannotation 3 inches from the top border of the page, you would use \&quot;300\&quot; for the Y coordinate. | [default to undefined]
**iEzsignannotationWidth** | **number** | The Width of the Ezsignannotation.  Width is calculated at 100dpi (dot per inch). So for example, if you want to have the width of the Ezsignannotation to be 3 inches, you would use \&quot;300\&quot; for the Width. | [optional] [default to undefined]
**iEzsignannotationHeight** | **number** | The Height of the Ezsignannotation.  Height is calculated at 100dpi (dot per inch). So for example, if you want to have the height of the Ezsignannotation to be 2 inches, you would use \&quot;200\&quot; for the Height.  This can only be set if eEzsignannotationType is **StrikethroughBlock** or **Text** | [optional] [default to undefined]
**sEzsignannotationText** | **string** | The Text of the Ezsignannotation | [optional] [default to undefined]
**iEzsignpagePagenumber** | **number** | The page number in the Ezsigndocument | [default to undefined]
**objTextstylestatic** | [**TextstylestaticResponseCompound**](TextstylestaticResponseCompound.md) |  | [optional] [default to undefined]

## Example

```typescript
import { EzsignannotationResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignannotationResponseCompound = {
    pkiEzsignannotationID,
    fkiEzsigndocumentID,
    eEzsignannotationHorizontalalignment,
    eEzsignannotationVerticalalignment,
    eEzsignannotationType,
    iEzsignannotationX,
    iEzsignannotationY,
    iEzsignannotationWidth,
    iEzsignannotationHeight,
    sEzsignannotationText,
    iEzsignpagePagenumber,
    objTextstylestatic,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
