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



/**
 * An Ezsignpage Object
 * @export
 * @interface EzsignpageResponse
 */
export interface EzsignpageResponse {
    /**
     * The unique ID of the Ezsignpage
     * @type {number}
     * @memberof EzsignpageResponse
     */
    /*'pkiEzsignpageID': number;*/
    'pkiEzsignpageID': number;
    /**
     * The Width of the page\'s image in pixels calculated at 100 DPI
     * @type {number}
     * @memberof EzsignpageResponse
     */
    /*'iEzsignpageWidthimage': number;*/
    'iEzsignpageWidthimage': number;
    /**
     * The Height of the page\'s image in pixels calculated at 100 DPI
     * @type {number}
     * @memberof EzsignpageResponse
     */
    /*'iEzsignpageHeightimage': number;*/
    'iEzsignpageHeightimage': number;
    /**
     * The Width of the page in points calculated at 72 DPI
     * @type {number}
     * @memberof EzsignpageResponse
     */
    /*'iEzsignpageWidthpdf': number;*/
    'iEzsignpageWidthpdf': number;
    /**
     * The Height of the page in points calculated at 72 DPI
     * @type {number}
     * @memberof EzsignpageResponse
     */
    /*'iEzsignpageHeightpdf': number;*/
    'iEzsignpageHeightpdf': number;
    /**
     * The page number in the Ezsigndocument
     * @type {number}
     * @memberof EzsignpageResponse
     */
    /*'iEzsignpagePagenumber': number;*/
    'iEzsignpagePagenumber': number;
    /**
     * The Url to the Ezsignpage\'s rasterized image.  Url will expire after 5 minutes.
     * @type {string}
     * @memberof EzsignpageResponse
     */
    /*'sComputedImageurl': string;*/
    'sComputedImageurl': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignpageResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignpageResponse
 */
export class DataObjectEzsignpageResponse {
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
 * A EzsignpageResponse Validation Object
 * @class ValidationObjectEzsignpageResponse
 */
export class ValidationObjectEzsignpageResponse {
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


