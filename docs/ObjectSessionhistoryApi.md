# ObjectSessionhistoryApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**sessionhistoryGetListV1**](#sessionhistorygetlistv1) | **GET** /1/object/sessionhistory/getList | Retrieve Sessionhistory list|

# **sessionhistoryGetListV1**
> SessionhistoryGetListV1Response sessionhistoryGetListV1()


### Example

```typescript
import {
    ObjectSessionhistoryApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectSessionhistoryApi(configuration);

let eOrderBy: 'pkiSessionhistoryID_ASC' | 'pkiSessionhistoryID_DESC' | 'fkiComputerID_ASC' | 'fkiComputerID_DESC' | 'fkiUserID_ASC' | 'fkiUserID_DESC' | 'dtSessionhistoryFirsthit_ASC' | 'dtSessionhistoryFirsthit_DESC' | 'dtSessionhistoryLasthit_ASC' | 'dtSessionhistoryLasthit_DESC' | 'eSessionhistoryEndby_ASC' | 'eSessionhistoryEndby_DESC' | 'sComputerDescription_ASC' | 'sComputerDescription_DESC' | 'sSessionhistoryDuration_ASC' | 'sSessionhistoryDuration_DESC' | 'sSessionhistoryIP_ASC' | 'sSessionhistoryIP_DESC' | 'sUserLoginname_ASC' | 'sUserLoginname_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.sessionhistoryGetListV1(
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
| **eOrderBy** | [**&#39;pkiSessionhistoryID_ASC&#39; | &#39;pkiSessionhistoryID_DESC&#39; | &#39;fkiComputerID_ASC&#39; | &#39;fkiComputerID_DESC&#39; | &#39;fkiUserID_ASC&#39; | &#39;fkiUserID_DESC&#39; | &#39;dtSessionhistoryFirsthit_ASC&#39; | &#39;dtSessionhistoryFirsthit_DESC&#39; | &#39;dtSessionhistoryLasthit_ASC&#39; | &#39;dtSessionhistoryLasthit_DESC&#39; | &#39;eSessionhistoryEndby_ASC&#39; | &#39;eSessionhistoryEndby_DESC&#39; | &#39;sComputerDescription_ASC&#39; | &#39;sComputerDescription_DESC&#39; | &#39;sSessionhistoryDuration_ASC&#39; | &#39;sSessionhistoryDuration_DESC&#39; | &#39;sSessionhistoryIP_ASC&#39; | &#39;sSessionhistoryIP_DESC&#39; | &#39;sUserLoginname_ASC&#39; | &#39;sUserLoginname_DESC&#39;**]**Array<&#39;pkiSessionhistoryID_ASC&#39; &#124; &#39;pkiSessionhistoryID_DESC&#39; &#124; &#39;fkiComputerID_ASC&#39; &#124; &#39;fkiComputerID_DESC&#39; &#124; &#39;fkiUserID_ASC&#39; &#124; &#39;fkiUserID_DESC&#39; &#124; &#39;dtSessionhistoryFirsthit_ASC&#39; &#124; &#39;dtSessionhistoryFirsthit_DESC&#39; &#124; &#39;dtSessionhistoryLasthit_ASC&#39; &#124; &#39;dtSessionhistoryLasthit_DESC&#39; &#124; &#39;eSessionhistoryEndby_ASC&#39; &#124; &#39;eSessionhistoryEndby_DESC&#39; &#124; &#39;sComputerDescription_ASC&#39; &#124; &#39;sComputerDescription_DESC&#39; &#124; &#39;sSessionhistoryDuration_ASC&#39; &#124; &#39;sSessionhistoryDuration_DESC&#39; &#124; &#39;sSessionhistoryIP_ASC&#39; &#124; &#39;sSessionhistoryIP_DESC&#39; &#124; &#39;sUserLoginname_ASC&#39; &#124; &#39;sUserLoginname_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**SessionhistoryGetListV1Response**

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

