/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import { UsergroupEditUsergroupdelegationsV1ResponseMPayload } from './usergroup-edit-usergroupdelegations-v1-response-mpayload';

/**
 * @type UsergroupEditUsergroupdelegationsV1Response
 * Response for PUT /1/object/usergroup/{pkiUsergroupID}/editUsergroupdelegations
 * @export
 */
/*export type UsergroupEditUsergroupdelegationsV1Response = CommonResponse;*/
export interface UsergroupEditUsergroupdelegationsV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof UsergroupEditUsergroupdelegationsV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof UsergroupEditUsergroupdelegationsV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {UsergroupEditUsergroupdelegationsV1ResponseMPayload}
     * @memberof UsergroupEditUsergroupdelegationsV1Response
     */
    mPayload:UsergroupEditUsergroupdelegationsV1ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { DataObjectUsergroupEditUsergroupdelegationsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectUsergroupEditUsergroupdelegationsV1ResponseMPayload } from './'

/**
 * @export 
 * A UsergroupEditUsergroupdelegationsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupEditUsergroupdelegationsV1Response
 */
export class DataObjectUsergroupEditUsergroupdelegationsV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:UsergroupEditUsergroupdelegationsV1ResponseMPayload = new DataObjectUsergroupEditUsergroupdelegationsV1ResponseMPayload()
}

/**
 * @export 
 * A UsergroupEditUsergroupdelegationsV1Response Validation Object
 * @class ValidationObjectUsergroupEditUsergroupdelegationsV1Response
 */
export class ValidationObjectUsergroupEditUsergroupdelegationsV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectUsergroupEditUsergroupdelegationsV1ResponseMPayload()
} 


