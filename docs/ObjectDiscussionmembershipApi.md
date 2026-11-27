# ObjectDiscussionmembershipApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**discussionmembershipCreateObjectV1**](#discussionmembershipcreateobjectv1) | **POST** /1/object/discussionmembership | Create a new Discussionmembership|
|[**discussionmembershipDeleteObjectV1**](#discussionmembershipdeleteobjectv1) | **DELETE** /1/object/discussionmembership/{pkiDiscussionmembershipID} | Delete an existing Discussionmembership|

# **discussionmembershipCreateObjectV1**
> DiscussionmembershipCreateObjectV1Response discussionmembershipCreateObjectV1(discussionmembershipCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectDiscussionmembershipApi,
    Configuration,
    DiscussionmembershipCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDiscussionmembershipApi(configuration);

let discussionmembershipCreateObjectV1Request: DiscussionmembershipCreateObjectV1Request; //

const { status, data } = await apiInstance.discussionmembershipCreateObjectV1(
    discussionmembershipCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **discussionmembershipCreateObjectV1Request** | **DiscussionmembershipCreateObjectV1Request**|  | |


### Return type

**DiscussionmembershipCreateObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**201** | Successful response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **discussionmembershipDeleteObjectV1**
> DiscussionmembershipDeleteObjectV1Response discussionmembershipDeleteObjectV1()



### Example

```typescript
import {
    ObjectDiscussionmembershipApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDiscussionmembershipApi(configuration);

let pkiDiscussionmembershipID: number; //The unique ID of the Discussionmembership (default to undefined)

const { status, data } = await apiInstance.discussionmembershipDeleteObjectV1(
    pkiDiscussionmembershipID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiDiscussionmembershipID** | [**number**] | The unique ID of the Discussionmembership | defaults to undefined|


### Return type

**DiscussionmembershipDeleteObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

