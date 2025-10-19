# EzsignformfieldResponse

An Ezsignformfield Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsignformfieldID** | **number** | The unique ID of the Ezsignformfield | [default to undefined]
**iEzsignpagePagenumber** | **number** | The page number in the Ezsigndocument | [default to undefined]
**sEzsignformfieldLabel** | **string** | The Label for the Ezsignformfield | [default to undefined]
**sEzsignformfieldValue** | **string** | The value for the Ezsignformfield  This can only be set if eEzsignformfieldgroupType is Checkbox or Radio | [optional] [default to undefined]
**iEzsignformfieldX** | **number** | The X coordinate (Horizontal) where to put the Ezsignformfield on the Ezsignpage.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsignformfield 2 inches from the left border of the page, you would use \&quot;200\&quot; for the X coordinate. | [default to undefined]
**iEzsignformfieldY** | **number** | The Y coordinate (Vertical) where to put the Ezsignformfield on the Ezsignpage.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsignformfield 3 inches from the top border of the page, you would use \&quot;300\&quot; for the Y coordinate. | [default to undefined]
**iEzsignformfieldWidth** | **number** | The Width of the Ezsignformfield in pixels calculated at 100 DPI | [default to undefined]
**iEzsignformfieldHeight** | **number** | The Height of the Ezsignformfield in pixels calculated at 100 DPI  | [default to undefined]
**bEzsignformfieldAutocomplete** | **boolean** | Whether the Ezsignformfield allows the use of the autocomplete of the browser.  This can only be set if eEzsignformfieldgroupType is **Text** | [optional] [default to undefined]
**bEzsignformfieldSelected** | **boolean** | Whether the Ezsignformfield is selected or not by default.  This can only be set if eEzsignformfieldgroupType is **Checkbox** or **Radio** | [optional] [default to undefined]
**sEzsignformfieldEnteredvalue** | **string** | This is the value enterred for the Ezsignformfield  This can only be set if eEzsignformfieldgroupType is **Dropdown**, **Text** or **Textarea** | [optional] [default to undefined]
**eEzsignformfieldDependencyrequirement** | [**FieldEEzsignformfieldDependencyrequirement**](FieldEEzsignformfieldDependencyrequirement.md) |  | [optional] [default to undefined]
**eEzsignformfieldHorizontalalignment** | [**EnumHorizontalalignment**](EnumHorizontalalignment.md) |  | [optional] [default to undefined]
**objTextstylestatic** | [**TextstylestaticResponseCompound**](TextstylestaticResponseCompound.md) |  | [optional] [default to undefined]

## Example

```typescript
import { EzsignformfieldResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignformfieldResponse = {
    pkiEzsignformfieldID,
    iEzsignpagePagenumber,
    sEzsignformfieldLabel,
    sEzsignformfieldValue,
    iEzsignformfieldX,
    iEzsignformfieldY,
    iEzsignformfieldWidth,
    iEzsignformfieldHeight,
    bEzsignformfieldAutocomplete,
    bEzsignformfieldSelected,
    sEzsignformfieldEnteredvalue,
    eEzsignformfieldDependencyrequirement,
    eEzsignformfieldHorizontalalignment,
    objTextstylestatic,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
