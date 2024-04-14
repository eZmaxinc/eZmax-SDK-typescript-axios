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
import { EzsignpageResponse } from './ezsignpage-response';

/**
 * @type EzsignpageResponseCompound
 * An Ezsignpage Object and children to create a complete structure
 * @export
 */
/*export type EzsignpageResponseCompound = EzsignpageResponse;*/
export interface EzsignpageResponseCompound {
    /**
     * The unique ID of the Ezsignpage
     * @type {number}
     * @memberof EzsignpageResponseCompound
     */
    pkiEzsignpageID:number 
    /**
     * The Width of the page\'s image in pixels calculated at 100 DPI
     * @type {number}
     * @memberof EzsignpageResponseCompound
     */
    iEzsignpageWidthimage:number 
    /**
     * The Height of the page\'s image in pixels calculated at 100 DPI
     * @type {number}
     * @memberof EzsignpageResponseCompound
     */
    iEzsignpageHeightimage:number 
    /**
     * The Width of the page in points calculated at 72 DPI
     * @type {number}
     * @memberof EzsignpageResponseCompound
     */
    iEzsignpageWidthpdf:number 
    /**
     * The Height of the page in points calculated at 72 DPI
     * @type {number}
     * @memberof EzsignpageResponseCompound
     */
    iEzsignpageHeightpdf:number 
    /**
     * The page number in the Ezsigndocument
     * @type {number}
     * @memberof EzsignpageResponseCompound
     */
    iEzsignpagePagenumber:number 
    /**
     * The Url to the Ezsignpage\'s rasterized image.  Url will expire after 5 minutes.
     * @type {string}
     * @memberof EzsignpageResponseCompound
     */
    sComputedImageurl:string 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignpageResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignpageResponseCompound
 */
export class DataObjectEzsignpageResponseCompound {
    pkiEzsignpageID:number = 0
    iEzsignpageWidthimage:number = 0
    iEzsignpageHeightimage:number = 0
    iEzsignpageWidthpdf:number = 0
    iEzsignpageHeightpdf:number = 0
    iEzsignpagePagenumber:number = 0
    sComputedImageurl:string = ''
}

/**
 * @export 
 * A EzsignpageResponseCompound Validation Object
 * @class ValidationObjectEzsignpageResponseCompound
 */
export class ValidationObjectEzsignpageResponseCompound {
   pkiEzsignpageID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsignpageWidthimage = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsignpageHeightimage = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsignpageWidthpdf = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsignpageHeightpdf = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsignpagePagenumber = {
      type: 'integer',
      minimum: 1,
      required: true
   }
   sComputedImageurl = {
      type: 'string',
      required: true
   }
} 


