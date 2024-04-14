/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CommonReportsection } from './common-reportsection';

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
} 


