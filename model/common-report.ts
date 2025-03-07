/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { CommonReportsection } from './common-reportsection';

/**
 * A Report containing Reportsections 
 * @export
 * @interface CommonReport
 */
export interface CommonReport {
    /**
     * 
     * @type {Array<CommonReportsection>}
     * @memberof CommonReport
     */
    /*'a_objReportsection': Array<CommonReportsection>;*/
    'a_objReportsection': Array<CommonReportsection>;
    /**
     * Whether we display pagination in the report
     * @type {boolean}
     * @memberof CommonReport
     */
    /*'bReportPaginate'?: boolean;*/
    'bReportPaginate'?: boolean;
    /**
     * The title of this Report
     * @type {string}
     * @memberof CommonReport
     */
    /*'sReportTitle'?: string;*/
    'sReportTitle'?: string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CommonReport Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCommonReport
 */
export class DataObjectCommonReport {
   a_objReportsection:Array<CommonReportsection> = []
   bReportPaginate?:boolean = undefined
   sReportTitle?:string = undefined
}

/**
 * @export 
 * A CommonReport Validation Object
 * @class ValidationObjectCommonReport
 */
export class ValidationObjectCommonReport {
   a_objReportsection = {
      type: 'array',
      required: true
   }
   bReportPaginate = {
      type: 'boolean',
      required: false
   }
   sReportTitle = {
      type: 'string',
      required: false
   }
} 


