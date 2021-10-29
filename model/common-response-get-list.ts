/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.3
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { CommonResponseObjDebug } from './common-response-obj-debug';
import { CommonResponseObjDebugPayloadGetList } from './common-response-obj-debug-payload-get-list';

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

