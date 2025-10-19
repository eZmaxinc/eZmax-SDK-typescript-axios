# CommonReportsubsection

A Subsection in a Reportsection. It contains 3 Reportsubsectionparts (Header, Body and Footer) 

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**a_objReportcolumn** | [**Array&lt;CommonReportcolumn&gt;**](CommonReportcolumn.md) |  | [default to undefined]
**iReportsubsectionColumncount** | **number** | The number of Reportcolumns in the Reportsection | [default to undefined]
**iReportsubsectionWidth** | **number** | The combined width of all the Reportcolumns in the Reportsection | [default to undefined]
**objReportsubsectionpartHeader** | [**CommonReportsubsectionpart**](CommonReportsubsectionpart.md) |  | [default to undefined]
**objReportsubsectionpartBody** | [**CommonReportsubsectionpart**](CommonReportsubsectionpart.md) |  | [default to undefined]
**objReportsubsectionpartFooter** | [**CommonReportsubsectionpart**](CommonReportsubsectionpart.md) |  | [default to undefined]
**sReportsubsectionTitle** | **string** | The title of this Reportsubsection | [optional] [default to undefined]

## Example

```typescript
import { CommonReportsubsection } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CommonReportsubsection = {
    a_objReportcolumn,
    iReportsubsectionColumncount,
    iReportsubsectionWidth,
    objReportsubsectionpartHeader,
    objReportsubsectionpartBody,
    objReportsubsectionpartFooter,
    sReportsubsectionTitle,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
