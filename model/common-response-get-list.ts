/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayloadGetList } from './common-response-obj-debug-payload-get-list';

import { DefaultObject } from '../base'

/**
 * All API response will inherit this based Response
 * @export
 * @interface CommonResponseGetList
 */
export interface CommonResponseGetList {
    /**
     * 
     * @type {CommonResponseObjDebugPayloadGetList}
     * @memberof CommonResponseGetList
     */
    'objDebugPayload'?: CommonResponseObjDebugPayloadGetList;
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof CommonResponseGetList
     */
    'objDebug'?: CommonResponseObjDebug;
}
/**
 * A CommonResponseGetList Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectCommonResponseGetList
 */
export class DefaultObjectCommonResponseGetList extends DefaultObject {
   objDebugPayload?:Partial<CommonResponseObjDebugPayloadGetList> = undefined
   objDebug?:Partial<CommonResponseObjDebug> = undefined
}


