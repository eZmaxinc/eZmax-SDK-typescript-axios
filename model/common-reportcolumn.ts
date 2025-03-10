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
import type { CommonReportcellstyle } from './common-reportcellstyle';
// May contain unused imports in some cases
// @ts-ignore
import type { EnumReportdataType } from './enum-reportdata-type';

/**
 * A column in a Reportsection 
 * @export
 * @interface CommonReportcolumn
 */
export interface CommonReportcolumn {
    /**
     * 
     * @type {CommonReportcellstyle}
     * @memberof CommonReportcolumn
     */
    /*'objReportcellstyleDefault': CommonReportcellstyle;*/
    'objReportcellstyleDefault': CommonReportcellstyle;
    /**
     * The Reportcolumn width in pixels
     * @type {number}
     * @memberof CommonReportcolumn
     */
    /*'iReportcolumnWidth': number;*/
    'iReportcolumnWidth': number;
    /**
     * 
     * @type {EnumReportdataType}
     * @memberof CommonReportcolumn
     */
    /*'eReportcolumnType': EnumReportdataType;*/
    'eReportcolumnType': EnumReportdataType;
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonReportcellstyle } from './'
// @ts-ignore
import { ValidationObjectCommonReportcellstyle } from './'

/**
 * @export 
 * A CommonReportcolumn Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCommonReportcolumn
 */
export class DataObjectCommonReportcolumn {
   objReportcellstyleDefault:CommonReportcellstyle = new DataObjectCommonReportcellstyle()
   iReportcolumnWidth:number = 0
   eReportcolumnType:EnumReportdataType = 'Date'
}

/**
 * @export 
 * A CommonReportcolumn Validation Object
 * @class ValidationObjectCommonReportcolumn
 */
export class ValidationObjectCommonReportcolumn {
   objReportcellstyleDefault = new ValidationObjectCommonReportcellstyle()
   iReportcolumnWidth = {
      type: 'integer',
      required: true
   }
   eReportcolumnType = {
      type: 'enum',
      allowableValues: ['Date','Money','Number','Percentage','Period','String'],
      required: true
   }
} 


