/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.8
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { CommonResponseObjDebug } from './common-response-obj-debug';
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';

/**
 * All API response will inherit this based Response
 * @export
 * @interface CommonResponse
 */
export interface CommonResponse {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof CommonResponse
     */
    'objDebugPayload'?: CommonResponseObjDebugPayload;
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof CommonResponse
     */
    'objDebug'?: CommonResponseObjDebug;
}

