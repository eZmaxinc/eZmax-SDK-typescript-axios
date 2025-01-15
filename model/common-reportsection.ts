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
import type { CommonReportcolumn } from './common-reportcolumn';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonReportsubsection } from './common-reportsubsection';
// May contain unused imports in some cases
// @ts-ignore
import type { EnumHorizontalalignment } from './enum-horizontalalignment';

/**
 * A section in a Report. Each Reportsection shares Reportcolumns disposition with all its Reportsubsection 
 * @export
 * @interface CommonReportsection
 */
export interface CommonReportsection {
    /**
     * 
     * @type {Array<CommonReportsubsection>}
     * @memberof CommonReportsection
     */
    /*'a_objReportsubsection': Array<CommonReportsubsection>;*/
    'a_objReportsubsection': Array<CommonReportsubsection>;
    /**
     * 
     * @type {Array<CommonReportcolumn>}
     * @memberof CommonReportsection
     */
    /*'a_objReportcolumn': Array<CommonReportcolumn>;*/
    'a_objReportcolumn': Array<CommonReportcolumn>;
    /**
     * 
     * @type {EnumHorizontalalignment}
     * @memberof CommonReportsection
     */
    /*'eReportsectionHorizontalalignment': EnumHorizontalalignment;*/
    'eReportsectionHorizontalalignment': EnumHorizontalalignment;
    /**
     * The number of Reportcolumns in the Reportsection
     * @type {number}
     * @memberof CommonReportsection
     */
    /*'iReportsectionColumncount': number;*/
    'iReportsectionColumncount': number;
    /**
     * The combined width of all the Reportcolumns in the Reportsection
     * @type {number}
     * @memberof CommonReportsection
     */
    /*'iReportsectionWidth': number;*/
    'iReportsectionWidth': number;
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CommonReportsection Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCommonReportsection
 */
export class DataObjectCommonReportsection {
   a_objReportsubsection:Array<CommonReportsubsection> = []
   a_objReportcolumn:Array<CommonReportcolumn> = []
   eReportsectionHorizontalalignment:EnumHorizontalalignment = 'Center'
   iReportsectionColumncount:number = 0
   iReportsectionWidth:number = 0
}

/**
 * @export 
 * A CommonReportsection Validation Object
 * @class ValidationObjectCommonReportsection
 */
export class ValidationObjectCommonReportsection {
   a_objReportsubsection = {
      type: 'array',
      required: true
   }
   a_objReportcolumn = {
      type: 'array',
      required: true
   }
   eReportsectionHorizontalalignment = {
      type: 'enum',
      allowableValues: ['Center','Left','Right'],
      required: true
   }
   iReportsectionColumncount = {
      type: 'integer',
      required: true
   }
   iReportsectionWidth = {
      type: 'integer',
      required: true
   }
} 


