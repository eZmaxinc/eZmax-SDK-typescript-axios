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
import { CommonReportsubsectionpart } from './common-reportsubsectionpart';

/**
 * A Subsection in a Reportsection. It contains 3 Reportsubsectionparts (Header, Body and Footer) 
 * @export
 * @interface CommonReportsubsection
 */
export interface CommonReportsubsection {
    /**
     * 
     * @type {CommonReportsubsectionpart}
     * @memberof CommonReportsubsection
     */
    'objReportsubsectionpartHeader': CommonReportsubsectionpart;
    /**
     * 
     * @type {CommonReportsubsectionpart}
     * @memberof CommonReportsubsection
     */
    'objReportsubsectionpartBody': CommonReportsubsectionpart;
    /**
     * 
     * @type {CommonReportsubsectionpart}
     * @memberof CommonReportsubsection
     */
    'objReportsubsectionpartFooter': CommonReportsubsectionpart;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonReportsubsectionpart } from './'
// @ts-ignore
import { DataObjectCommonReportsubsectionpart } from './'
// @ts-ignore
import { DataObjectCommonReportsubsectionpart } from './'
// @ts-ignore
import { ValidationObjectCommonReportsubsectionpart } from './'
// @ts-ignore
import { ValidationObjectCommonReportsubsectionpart } from './'
// @ts-ignore
import { ValidationObjectCommonReportsubsectionpart } from './'

/**
 * @export 
 * A CommonReportsubsection Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCommonReportsubsection
 */
export class DataObjectCommonReportsubsection {
   objReportsubsectionpartHeader:CommonReportsubsectionpart = new DataObjectCommonReportsubsectionpart()
   objReportsubsectionpartBody:CommonReportsubsectionpart = new DataObjectCommonReportsubsectionpart()
   objReportsubsectionpartFooter:CommonReportsubsectionpart = new DataObjectCommonReportsubsectionpart()
}

/**
 * @export 
 * A CommonReportsubsection Validation Object
 * @class ValidationObjectCommonReportsubsection
 */
export class ValidationObjectCommonReportsubsection {
   objReportsubsectionpartHeader = new ValidationObjectCommonReportsubsectionpart()
   objReportsubsectionpartBody = new ValidationObjectCommonReportsubsectionpart()
   objReportsubsectionpartFooter = new ValidationObjectCommonReportsubsectionpart()
} 


