/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseFilter } from './common-response-filter';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayloadGetListAllOf } from './common-response-obj-debug-payload-get-list-all-of';

import { DefaultObject } from '../base'

/**
 * @type CommonResponseObjDebugPayloadGetList
 * This is a debug object containing debugging information on the actual function
 * @export
 */
export type CommonResponseObjDebugPayloadGetList = CommonResponseObjDebugPayload & CommonResponseObjDebugPayloadGetListAllOf;


/**
 * @export 
 * A CommonResponseObjDebugPayloadGetList Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectCommonResponseObjDebugPayloadGetList
 */
export class DefaultObjectCommonResponseObjDebugPayloadGetList extends DefaultObject {
   iVersionMin:number = 0
   iVersionMax:number = 0
   a_RequiredPermission:Array<number> = []
   a_Filter:Partial<CommonResponseFilter> = {}
   a_OrderBy:{ [key: string]: string; } = {}
}


