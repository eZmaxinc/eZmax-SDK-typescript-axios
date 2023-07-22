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
import { CommonReportrow } from './common-reportrow';

/**
 * A part in the Reportsubsection 
 * @export
 * @interface CommonReportsubsectionpart
 */
export interface CommonReportsubsectionpart {
    /**
     * The type of the Reportsubsectionpart
     * @type {string}
     * @memberof CommonReportsubsectionpart
     */
    'eReportsubsectionpartType': CommonReportsubsectionpartEReportsubsectionpartTypeEnum;
    /**
     * 
     * @type {Array<CommonReportrow>}
     * @memberof CommonReportsubsectionpart
     */
    'a_objReportrow': Array<CommonReportrow>;
}

export const CommonReportsubsectionpartEReportsubsectionpartTypeEnum = {
    Header: 'Header',
    Body: 'Body',
    Footer: 'Footer'
} as const;
export type CommonReportsubsectionpartEReportsubsectionpartTypeEnum = typeof CommonReportsubsectionpartEReportsubsectionpartTypeEnum[keyof typeof CommonReportsubsectionpartEReportsubsectionpartTypeEnum];


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CommonReportsubsectionpart Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCommonReportsubsectionpart
 */
export class DataObjectCommonReportsubsectionpart {
   eReportsubsectionpartType:CommonReportsubsectionpartEReportsubsectionpartTypeEnum = 'Header'
   a_objReportrow:Array<CommonReportrow> = []
}

/**
 * @export 
 * A CommonReportsubsectionpart Validation Object
 * @class ValidationObjectCommonReportsubsectionpart
 */
export class ValidationObjectCommonReportsubsectionpart {
   eReportsubsectionpartType = {
      type: 'enum',
      allowableValues: ['Header','Body','Footer'],
      required: true
   }
   a_objReportrow = {
      type: 'array',
      required: true
   }
} 


