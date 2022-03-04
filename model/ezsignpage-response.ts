/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.6
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
    'pkiEzsignpageID': number;
    /**
     * The Width of the page\'s image in pixels calculated at 100 DPI
     * @type {number}
     * @memberof EzsignpageResponse
     */
    'iEzsignpageWidthimage': number;
    /**
     * The Height of the page\'s image in pixels calculated at 100 DPI
     * @type {number}
     * @memberof EzsignpageResponse
     */
    'iEzsignpageHeightimage': number;
    /**
     * The Width of the page in points calculated at 72 DPI
     * @type {number}
     * @memberof EzsignpageResponse
     */
    'iEzsignpageWidthpdf': number;
    /**
     * The Height of the page in points calculated at 72 DPI
     * @type {number}
     * @memberof EzsignpageResponse
     */
    'iEzsignpageHeightpdf': number;
    /**
     * The page number in the Ezsigndocument
     * @type {number}
     * @memberof EzsignpageResponse
     */
    'iEzsignpagePagenumber': number;
    /**
     * The Url to the Ezsignpage\'s rasterized image.  Url will expire after 5 minutes.
     * @type {string}
     * @memberof EzsignpageResponse
     */
    'sImageUrl': string;
}

