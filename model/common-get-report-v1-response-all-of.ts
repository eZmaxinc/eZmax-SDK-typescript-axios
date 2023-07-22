/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CommonGetReportV1ResponseMPayload } from './common-get-report-v1-response-mpayload';

/**
 * 
 * @export
 * @interface CommonGetReportV1ResponseAllOf
 */
export interface CommonGetReportV1ResponseAllOf {
    /**
     * 
     * @type {CommonGetReportV1ResponseMPayload}
     * @memberof CommonGetReportV1ResponseAllOf
     */
    'mPayload': CommonGetReportV1ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonGetReportV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonGetReportV1ResponseMPayload } from './'

/**
 * @export 
 * A CommonGetReportV1ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCommonGetReportV1ResponseAllOf
 */
export class DataObjectCommonGetReportV1ResponseAllOf {
   mPayload:CommonGetReportV1ResponseMPayload = new DataObjectCommonGetReportV1ResponseMPayload()
}

/**
 * @export 
 * A CommonGetReportV1ResponseAllOf Validation Object
 * @class ValidationObjectCommonGetReportV1ResponseAllOf
 */
export class ValidationObjectCommonGetReportV1ResponseAllOf {
   mPayload = new ValidationObjectCommonGetReportV1ResponseMPayload()
} 


