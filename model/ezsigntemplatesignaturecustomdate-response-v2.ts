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



/**
 * An Ezsigntemplatesignaturecustomdate Object
 * @export
 * @interface EzsigntemplatesignaturecustomdateResponseV2
 */
export interface EzsigntemplatesignaturecustomdateResponseV2 {
    /**
     * The unique ID of the Ezsigntemplatesignaturecustomdate
     * @type {number}
     * @memberof EzsigntemplatesignaturecustomdateResponseV2
     */
    /*'pkiEzsigntemplatesignaturecustomdateID': number;*/
    'pkiEzsigntemplatesignaturecustomdateID': number;
    /**
     * The X coordinate (Horizontal) where to put the Ezsigntemplatesignaturecustomdate on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsigntemplatesignaturecustomdate 2 inches from the left of the signature, you would use \"200\" for the X coordinate.
     * @type {number}
     * @memberof EzsigntemplatesignaturecustomdateResponseV2
     */
    /*'iEzsigntemplatesignaturecustomdateOffsetx': number;*/
    'iEzsigntemplatesignaturecustomdateOffsetx': number;
    /**
     * The X coordinate (Horizontal) where to put the Ezsigntemplatesignaturecustomdate on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsigntemplatesignaturecustomdate 2 inches from the top of the signature, you would use \"200\" for the Y coordinate.
     * @type {number}
     * @memberof EzsigntemplatesignaturecustomdateResponseV2
     */
    /*'iEzsigntemplatesignaturecustomdateOffsety': number;*/
    'iEzsigntemplatesignaturecustomdateOffsety': number;
    /**
     * The custom date format to use  You can use the codes below and they will be replaced at signature time. Text values like month and day names will be rendered in the proper language. Other text will be left as-is.  The codes examples below are based on the following datetime: Thursday, January 6, 2022 at 08:07:09 EST  For example, the format \"Signature date: {MM}/{DD}/{YYYY} {hh}:{mm}\" would become \"Signature date: 01/06/2022 08:07\"  **Year**  | Code | Example | | - | - | | {YYYY} | 2022 | | {YY} | 22 |  **Month**  | Code | Example | | - | - | | {MonthCapitalize} | Janvier | | {Month} | janvier | | {MM} | 01 | | {M} | 1 |  **Day**  | Code | Example | | - | - | | {DayCapitalize} | Jeudi | | {Day} | jeudi | | {DD} | 06 | | {D} | 6 |  **Hour**  | Code | Example | | - | - | | {hh} | 08 |  **Minute**  | Code | Example | | - | - | | {mm} | 07 |  **Second**  | Code | Example | | - | - | | {ss} | 09 |        **Timezone**  | Code | Example | | - | - | | {Z} | EST |       **Time**  | Code | Example | | - | - | | {Time} | 08:07:09 |   | {TimeZ} | 08:07:09 EST |     **Date**  | Code | Example | | - | - | | {Date} | 2022-01-06 |   | {DateText} | 1er Janvier 2022 |  **Full**  | Code | Example | | - | - | | {DateTime} | 2022-01-06 08:07:09 |   | {DateTimeZ} | 2022-01-06 08:07:09 EST | 
     * @type {string}
     * @memberof EzsigntemplatesignaturecustomdateResponseV2
     */
    /*'sEzsigntemplatesignaturecustomdateFormat': string;*/
    'sEzsigntemplatesignaturecustomdateFormat': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatesignaturecustomdateResponseV2 Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatesignaturecustomdateResponseV2
 */
export class DataObjectEzsigntemplatesignaturecustomdateResponseV2 {
   pkiEzsigntemplatesignaturecustomdateID:number = 0
   iEzsigntemplatesignaturecustomdateOffsetx:number = 0
   iEzsigntemplatesignaturecustomdateOffsety:number = 0
   sEzsigntemplatesignaturecustomdateFormat:string = ''
}

/**
 * @export 
 * A EzsigntemplatesignaturecustomdateResponseV2 Validation Object
 * @class ValidationObjectEzsigntemplatesignaturecustomdateResponseV2
 */
export class ValidationObjectEzsigntemplatesignaturecustomdateResponseV2 {
   pkiEzsigntemplatesignaturecustomdateID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsigntemplatesignaturecustomdateOffsetx = {
      type: 'integer',
      required: true
   }
   iEzsigntemplatesignaturecustomdateOffsety = {
      type: 'integer',
      required: true
   }
   sEzsigntemplatesignaturecustomdateFormat = {
      type: 'string',
      required: true
   }
} 


