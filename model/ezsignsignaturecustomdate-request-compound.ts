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
import { EzsignsignaturecustomdateRequest } from './ezsignsignaturecustomdate-request';

/**
 * @type EzsignsignaturecustomdateRequestCompound
 * An Ezsignsignaturecustomdate Object and children to create a complete structure
 * @export
 */
/** export type EzsignsignaturecustomdateRequestCompound = EzsignsignaturecustomdateRequest; */
export interface EzsignsignaturecustomdateRequestCompound {
    /**
     * The unique ID of the Ezsignsignaturecustomdate
     * @type {number}
     * @memberof EzsignsignaturecustomdateRequestCompound
     */
    pkiEzsignsignaturecustomdateID?:number 
    /**
     * The X coordinate (Horizontal) where to put the Ezsignsignaturecustomdate on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsignsignaturecustomdate block 2 inches from the left border of the page, you would use \"200\" for the X coordinate.
     * @type {number}
     * @memberof EzsignsignaturecustomdateRequestCompound
     */
    iEzsignsignaturecustomdateX:number 
    /**
     * The Y coordinate (Vertical) where to put the Ezsignsignaturecustomdate on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsignsignaturecustomdate block 3 inches from the top border of the page, you would use \"300\" for the Y coordinate.
     * @type {number}
     * @memberof EzsignsignaturecustomdateRequestCompound
     */
    iEzsignsignaturecustomdateY:number 
    /**
     * The custom date format to use  You can use the codes below and they will be replaced at signature time. Text values like month and day names will be rendered in the proper language. Other text will be left as-is.  The codes examples below are based on the following datetime: Thursday, January 6, 2022 at 08:07:09 EST  For example, the format \"Signature date: {MM}/{DD}/{YYYY} {hh}:{mm}\" would become \"Signature date: 01/06/2022 08:07\"  **Year**  | Code | Example | | - | - | | {YYYY} | 2022 | | {YY} | 22 |  **Month**  | Code | Example | | - | - | | {MonthCapitalize} | Janvier | | {Month} | janvier | | {MM} | 01 | | {M} | 1 |  **Day**  | Code | Example | | - | - | | {DayCapitalize} | Jeudi | | {Day} | jeudi | | {DD} | 06 | | {D} | 6 |  **Hour**  | Code | Example | | - | - | | {hh} | 08 |  **Minute**  | Code | Example | | - | - | | {mm} | 07 |  **Second**  | Code | Example | | - | - | | {ss} | 09 |        **Timezone**  | Code | Example | | - | - | | {Z} | EST |       **Time**  | Code | Example | | - | - | | {Time} | 08:07:09 |   | {TimeZ} | 08:07:09 EST |     **Date**  | Code | Example | | - | - | | {Date} | 2022-01-06 |   | {DateText} | 1er Janvier 2022 |  **Full**  | Code | Example | | - | - | | {DateTime} | 2022-01-06 08:07:09 |   | {DateTimeZ} | 2022-01-06 08:07:09 EST | 
     * @type {string}
     * @memberof EzsignsignaturecustomdateRequestCompound
     */
    sEzsignsignaturecustomdateFormat:string 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignsignaturecustomdateRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignaturecustomdateRequestCompound
 */
export class DataObjectEzsignsignaturecustomdateRequestCompound {
    pkiEzsignsignaturecustomdateID?:number = undefined
    iEzsignsignaturecustomdateX:number = 0
    iEzsignsignaturecustomdateY:number = 0
    sEzsignsignaturecustomdateFormat:string = ''
}

/**
 * @export 
 * A EzsignsignaturecustomdateRequestCompound Validation Object
 * @class ValidationObjectEzsignsignaturecustomdateRequestCompound
 */
export class ValidationObjectEzsignsignaturecustomdateRequestCompound {
   pkiEzsignsignaturecustomdateID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   iEzsignsignaturecustomdateX = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsignsignaturecustomdateY = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sEzsignsignaturecustomdateFormat = {
      type: 'string',
      required: true
   }
} 


