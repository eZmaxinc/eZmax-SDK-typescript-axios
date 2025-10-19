# EzsigntemplatesignaturecustomdateRequestCompound

An Ezsigntemplatesignaturecustomdate Object and children to create a complete structure

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsigntemplatesignaturecustomdateID** | **number** | The unique ID of the Ezsigntemplatesignaturecustomdate | [optional] [default to undefined]
**iEzsigntemplatesignaturecustomdateX** | **number** | The X coordinate (Horizontal) where to put the Ezsigntemplatesignaturecustomdate on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsigntemplatesignaturecustomdate 2 inches from the left border of the page, you would use \&quot;200\&quot; for the X coordinate. | [optional] [default to undefined]
**iEzsigntemplatesignaturecustomdateY** | **number** | The Y coordinate (Vertical) where to put the Ezsigntemplatesignaturecustomdate on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsigntemplatesignaturecustomdate 3 inches from the top border of the page, you would use \&quot;300\&quot; for the Y coordinate. | [optional] [default to undefined]
**iEzsigntemplatesignaturecustomdateOffsetx** | **number** | The X coordinate (Horizontal) where to put the Ezsigntemplatesignaturecustomdate on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsigntemplatesignaturecustomdate 2 inches from the left of the signature, you would use \&quot;200\&quot; for the X coordinate. | [optional] [default to undefined]
**iEzsigntemplatesignaturecustomdateOffsety** | **number** | The X coordinate (Horizontal) where to put the Ezsigntemplatesignaturecustomdate on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsigntemplatesignaturecustomdate 2 inches from the top of the signature, you would use \&quot;200\&quot; for the Y coordinate. | [optional] [default to undefined]
**sEzsigntemplatesignaturecustomdateFormat** | **string** | The custom date format to use  You can use the codes below and they will be replaced at signature time. Text values like month and day names will be rendered in the proper language. Other text will be left as-is.  The codes examples below are based on the following datetime: Thursday, January 6, 2022 at 08:07:09 EST  For example, the format \&quot;Signature date: {MM}/{DD}/{YYYY} {hh}:{mm}\&quot; would become \&quot;Signature date: 01/06/2022 08:07\&quot;  **Year**  | Code | Example | | - | - | | {YYYY} | 2022 | | {YY} | 22 |  **Month**  | Code | Example | | - | - | | {MonthCapitalize} | Janvier | | {Month} | janvier | | {MM} | 01 | | {M} | 1 |  **Day**  | Code | Example | | - | - | | {DayCapitalize} | Jeudi | | {Day} | jeudi | | {DD} | 06 | | {D} | 6 |  **Hour**  | Code | Example | | - | - | | {hh} | 08 |  **Minute**  | Code | Example | | - | - | | {mm} | 07 |  **Second**  | Code | Example | | - | - | | {ss} | 09 |        **Timezone**  | Code | Example | | - | - | | {Z} | EST |       **Time**  | Code | Example | | - | - | | {Time} | 08:07:09 |   | {TimeZ} | 08:07:09 EST |     **Date**  | Code | Example | | - | - | | {Date} | 2022-01-06 |   | {DateText} | 1er Janvier 2022 |  **Full**  | Code | Example | | - | - | | {DateTime} | 2022-01-06 08:07:09 |   | {DateTimeZ} | 2022-01-06 08:07:09 EST |  | [default to undefined]

## Example

```typescript
import { EzsigntemplatesignaturecustomdateRequestCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigntemplatesignaturecustomdateRequestCompound = {
    pkiEzsigntemplatesignaturecustomdateID,
    iEzsigntemplatesignaturecustomdateX,
    iEzsigntemplatesignaturecustomdateY,
    iEzsigntemplatesignaturecustomdateOffsetx,
    iEzsigntemplatesignaturecustomdateOffsety,
    sEzsigntemplatesignaturecustomdateFormat,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
