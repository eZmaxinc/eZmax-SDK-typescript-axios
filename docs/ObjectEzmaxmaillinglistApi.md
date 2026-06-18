# ObjectEzmaxmaillinglistApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezmaxmaillinglistGetListV1**](#ezmaxmaillinglistgetlistv1) | **GET** /1/object/ezmaxmaillinglist/getList | Retrieve Ezmaxmaillinglist list|

# **ezmaxmaillinglistGetListV1**
> EzmaxmaillinglistGetListV1Response ezmaxmaillinglistGetListV1()



### Example

```typescript
import {
    ObjectEzmaxmaillinglistApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzmaxmaillinglistApi(configuration);

let eOrderBy: 'pkiEzmaxmaillinglistID_ASC' | 'pkiEzmaxmaillinglistID_DESC' | 'sEzmaxmaillinglistNameX_ASC' | 'sEzmaxmaillinglistNameX_DESC' | 'sEzmaxmaillinglistDescriptionX_ASC' | 'sEzmaxmaillinglistDescriptionX_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.ezmaxmaillinglistGetListV1(
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
| **eOrderBy** | [**&#39;pkiEzmaxmaillinglistID_ASC&#39; | &#39;pkiEzmaxmaillinglistID_DESC&#39; | &#39;sEzmaxmaillinglistNameX_ASC&#39; | &#39;sEzmaxmaillinglistNameX_DESC&#39; | &#39;sEzmaxmaillinglistDescriptionX_ASC&#39; | &#39;sEzmaxmaillinglistDescriptionX_DESC&#39;**]**Array<&#39;pkiEzmaxmaillinglistID_ASC&#39; &#124; &#39;pkiEzmaxmaillinglistID_DESC&#39; &#124; &#39;sEzmaxmaillinglistNameX_ASC&#39; &#124; &#39;sEzmaxmaillinglistNameX_DESC&#39; &#124; &#39;sEzmaxmaillinglistDescriptionX_ASC&#39; &#124; &#39;sEzmaxmaillinglistDescriptionX_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**EzmaxmaillinglistGetListV1Response**

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

