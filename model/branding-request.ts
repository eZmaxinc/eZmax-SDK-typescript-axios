/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.12
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { FieldEBrandingLogo } from './field-ebranding-logo';
// May contain unused imports in some cases
// @ts-ignore
import { MultilingualBrandingDescription } from './multilingual-branding-description';

import { DefaultObject } from '../base'

/**
 * A Branding Object
 * @export
 * @interface BrandingRequest
 */
export interface BrandingRequest {
    /**
     * The unique ID of the Branding
     * @type {number}
     * @memberof BrandingRequest
     */
    'pkiBrandingID'?: number;
    /**
     * 
     * @type {MultilingualBrandingDescription}
     * @memberof BrandingRequest
     */
    'objBrandingDescription': MultilingualBrandingDescription;
    /**
     * 
     * @type {FieldEBrandingLogo}
     * @memberof BrandingRequest
     */
    'eBrandingLogo': FieldEBrandingLogo;
    /**
     * The Base64 encoded binary content of the branding logo. This need to match image type selected in eBrandingLogo if you supply an image. If you select \'Default\', the logo will be deleted and the default one will be used.
     * @type {string}
     * @memberof BrandingRequest
     */
    'sBrandingBase64'?: string;
    /**
     * The color of the text. This is a RGB color converted into integer
     * @type {number}
     * @memberof BrandingRequest
     */
    'iBrandingColortext': number;
    /**
     * The color of the text in the link box. This is a RGB color converted into integer
     * @type {number}
     * @memberof BrandingRequest
     */
    'iBrandingColortextlinkbox': number;
    /**
     * The color of the text in the button. This is a RGB color converted into integer
     * @type {number}
     * @memberof BrandingRequest
     */
    'iBrandingColortextbutton': number;
    /**
     * The color of the background. This is a RGB color converted into integer
     * @type {number}
     * @memberof BrandingRequest
     */
    'iBrandingColorbackground': number;
    /**
     * The color of the background of the button. This is a RGB color converted into integer
     * @type {number}
     * @memberof BrandingRequest
     */
    'iBrandingColorbackgroundbutton': number;
    /**
     * The color of the background of the small box. This is a RGB color converted into integer
     * @type {number}
     * @memberof BrandingRequest
     */
    'iBrandingColorbackgroundsmallbox': number;
    /**
     * Whether the Branding is active or not
     * @type {boolean}
     * @memberof BrandingRequest
     */
    'bBrandingIsactive': boolean;
}
/**
 * A BrandingRequest Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectBrandingRequest
 */
export class DefaultObjectBrandingRequest extends DefaultObject {
   pkiBrandingID?:number = undefined
   objBrandingDescription:Partial<MultilingualBrandingDescription> = {}
   eBrandingLogo:FieldEBrandingLogo = 'Default'
   sBrandingBase64?:string = undefined
   iBrandingColortext:number = 0
   iBrandingColortextlinkbox:number = 0
   iBrandingColortextbutton:number = 0
   iBrandingColorbackground:number = 0
   iBrandingColorbackgroundbutton:number = 0
   iBrandingColorbackgroundsmallbox:number = 0
   bBrandingIsactive:boolean = false
}


