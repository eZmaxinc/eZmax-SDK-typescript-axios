# ObjectAdjustmentreminderApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**adjustmentreminderGetListV1**](#adjustmentremindergetlistv1) | **GET** /1/object/adjustmentreminder/getList | Retrieve Adjustmentreminder list|

# **adjustmentreminderGetListV1**
> AdjustmentreminderGetListV1Response adjustmentreminderGetListV1()

Enum values that can be filtered in query parameter *sFilter*:  | Variable | Valid values | |---|---| | eAdjustmentreminderType | Inversion<br>Copy |

### Example

```typescript
import {
    ObjectAdjustmentreminderApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectAdjustmentreminderApi(configuration);

let eOrderBy: 'pkiAdjustmentreminderID_ASC' | 'pkiAdjustmentreminderID_DESC' | 'fkiAdjustmentID_ASC' | 'fkiAdjustmentID_DESC' | 'fkiPeriodID_ASC' | 'fkiPeriodID_DESC' | 'sPeriodYYYYMM_ASC' | 'sPeriodYYYYMM_DESC' | 'fkiUserIDCreated_ASC' | 'fkiUserIDCreated_DESC' | 'sUserLoginname_ASC' | 'sUserLoginname_DESC' | 'eAdjustmentreminderType_ASC' | 'eAdjustmentreminderType_DESC' | 'sAdjustmentNumber_ASC' | 'sAdjustmentNumber_DESC' | 'sAdjustmentComment_ASC' | 'sAdjustmentComment_DESC' | 'dAdjustmentTotaldebit_ASC' | 'dAdjustmentTotaldebit_DESC' | 'dAdjustmentTotalcredit_ASC' | 'dAdjustmentTotalcredit_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.adjustmentreminderGetListV1(
    eOrderBy,
    iRowMax,
    iRowOffset,
    acceptLanguage,
    sFilter
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **eOrderBy** | [**&#39;pkiAdjustmentreminderID_ASC&#39; | &#39;pkiAdjustmentreminderID_DESC&#39; | &#39;fkiAdjustmentID_ASC&#39; | &#39;fkiAdjustmentID_DESC&#39; | &#39;fkiPeriodID_ASC&#39; | &#39;fkiPeriodID_DESC&#39; | &#39;sPeriodYYYYMM_ASC&#39; | &#39;sPeriodYYYYMM_DESC&#39; | &#39;fkiUserIDCreated_ASC&#39; | &#39;fkiUserIDCreated_DESC&#39; | &#39;sUserLoginname_ASC&#39; | &#39;sUserLoginname_DESC&#39; | &#39;eAdjustmentreminderType_ASC&#39; | &#39;eAdjustmentreminderType_DESC&#39; | &#39;sAdjustmentNumber_ASC&#39; | &#39;sAdjustmentNumber_DESC&#39; | &#39;sAdjustmentComment_ASC&#39; | &#39;sAdjustmentComment_DESC&#39; | &#39;dAdjustmentTotaldebit_ASC&#39; | &#39;dAdjustmentTotaldebit_DESC&#39; | &#39;dAdjustmentTotalcredit_ASC&#39; | &#39;dAdjustmentTotalcredit_DESC&#39;**]**Array<&#39;pkiAdjustmentreminderID_ASC&#39; &#124; &#39;pkiAdjustmentreminderID_DESC&#39; &#124; &#39;fkiAdjustmentID_ASC&#39; &#124; &#39;fkiAdjustmentID_DESC&#39; &#124; &#39;fkiPeriodID_ASC&#39; &#124; &#39;fkiPeriodID_DESC&#39; &#124; &#39;sPeriodYYYYMM_ASC&#39; &#124; &#39;sPeriodYYYYMM_DESC&#39; &#124; &#39;fkiUserIDCreated_ASC&#39; &#124; &#39;fkiUserIDCreated_DESC&#39; &#124; &#39;sUserLoginname_ASC&#39; &#124; &#39;sUserLoginname_DESC&#39; &#124; &#39;eAdjustmentreminderType_ASC&#39; &#124; &#39;eAdjustmentreminderType_DESC&#39; &#124; &#39;sAdjustmentNumber_ASC&#39; &#124; &#39;sAdjustmentNumber_DESC&#39; &#124; &#39;sAdjustmentComment_ASC&#39; &#124; &#39;sAdjustmentComment_DESC&#39; &#124; &#39;dAdjustmentTotaldebit_ASC&#39; &#124; &#39;dAdjustmentTotaldebit_DESC&#39; &#124; &#39;dAdjustmentTotalcredit_ASC&#39; &#124; &#39;dAdjustmentTotalcredit_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**AdjustmentreminderGetListV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json, application/vnd.openxmlformats-officedocument.spreadsheetml.sheet


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**406** | The URL is valid, but one of the Accept header is not defined or invalid. For example, you set the header \&quot;Accept: application/json\&quot; but the function can only return \&quot;Content-type: image/png\&quot; |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

