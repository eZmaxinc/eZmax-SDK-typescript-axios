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
import { CommonReportgroup } from './common-reportgroup';

/**
 * Payload for POST /1/report/xxx/xxx and and /1/module/report/getReportFromCache
 * @export
 * @interface CommonGetReportV1ResponseMPayload
 */
export interface CommonGetReportV1ResponseMPayload {
    /**
     * 
     * @type {CommonReportgroup}
     * @memberof CommonGetReportV1ResponseMPayload
     */
    'objReportgroup': CommonReportgroup;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonReportgroup } from './'
// @ts-ignore
import { ValidationObjectCommonReportgroup } from './'

/**
 * @export 
 * A CommonGetReportV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCommonGetReportV1ResponseMPayload
 */
export class DataObjectCommonGetReportV1ResponseMPayload {
   objReportgroup:CommonReportgroup = new DataObjectCommonReportgroup()
}

/**
 * @export 
 * A CommonGetReportV1ResponseMPayload Validation Object
 * @class ValidationObjectCommonGetReportV1ResponseMPayload
 */
export class ValidationObjectCommonGetReportV1ResponseMPayload {
   objReportgroup = new ValidationObjectCommonReportgroup()
} 


