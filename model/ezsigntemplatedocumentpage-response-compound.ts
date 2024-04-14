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
import { EzsigntemplatedocumentpageResponse } from './ezsigntemplatedocumentpage-response';

/**
 * @type EzsigntemplatedocumentpageResponseCompound
 * An Ezsigntemplatedocumentpage Object and children to create a complete structure
 * @export
 */
/*export type EzsigntemplatedocumentpageResponseCompound = EzsigntemplatedocumentpageResponse;*/
export interface EzsigntemplatedocumentpageResponseCompound {
    /**
     * The unique ID of the Ezsigntemplatedocumentpage
     * @type {number}
     * @memberof EzsigntemplatedocumentpageResponseCompound
     */
    pkiEzsigntemplatedocumentpageID:number 
    /**
     * The Width of the page\'s image in pixels calculated at 100 DPI
     * @type {number}
     * @memberof EzsigntemplatedocumentpageResponseCompound
     */
    iEzsigntemplatedocumentpageWidthimage:number 
    /**
     * The Height of the page\'s image in pixels calculated at 100 DPI
     * @type {number}
     * @memberof EzsigntemplatedocumentpageResponseCompound
     */
    iEzsigntemplatedocumentpageHeightimage:number 
    /**
     * The Width of the page in points calculated at 72 DPI
     * @type {number}
     * @memberof EzsigntemplatedocumentpageResponseCompound
     */
    iEzsigntemplatedocumentpageWidthpdf:number 
    /**
     * The Height of the page in points calculated at 72 DPI
     * @type {number}
     * @memberof EzsigntemplatedocumentpageResponseCompound
     */
    iEzsigntemplatedocumentpageHeightpdf:number 
    /**
     * The page number in the Ezsigntemplatedocument
     * @type {number}
     * @memberof EzsigntemplatedocumentpageResponseCompound
     */
    iEzsigntemplatedocumentpagePagenumber:number 
    /**
     * The Url to the Ezsigntemplatedocumentpage\'s rasterized image.  Url will expire after 5 minutes.
     * @type {string}
     * @memberof EzsigntemplatedocumentpageResponseCompound
     */
    sComputedImageurl:string 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatedocumentpageResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatedocumentpageResponseCompound
 */
export class DataObjectEzsigntemplatedocumentpageResponseCompound {
    pkiEzsigntemplatedocumentpageID:number = 0
    iEzsigntemplatedocumentpageWidthimage:number = 0
    iEzsigntemplatedocumentpageHeightimage:number = 0
    iEzsigntemplatedocumentpageWidthpdf:number = 0
    iEzsigntemplatedocumentpageHeightpdf:number = 0
    iEzsigntemplatedocumentpagePagenumber:number = 0
    sComputedImageurl:string = ''
}

/**
 * @export 
 * A EzsigntemplatedocumentpageResponseCompound Validation Object
 * @class ValidationObjectEzsigntemplatedocumentpageResponseCompound
 */
export class ValidationObjectEzsigntemplatedocumentpageResponseCompound {
   pkiEzsigntemplatedocumentpageID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsigntemplatedocumentpageWidthimage = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsigntemplatedocumentpageHeightimage = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsigntemplatedocumentpageWidthpdf = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsigntemplatedocumentpageHeightpdf = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsigntemplatedocumentpagePagenumber = {
      type: 'integer',
      minimum: 1,
      required: true
   }
   sComputedImageurl = {
      type: 'string',
      required: true
   }
} 


