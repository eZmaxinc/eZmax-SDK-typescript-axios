/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { BrandingRequest } from './branding-request';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEBrandingLogo } from './field-ebranding-logo';
// May contain unused imports in some cases
// @ts-ignore
import { MultilingualBrandingDescription } from './multilingual-branding-description';

import { DefaultObject } from '../base'

/**
 * @type BrandingRequestCompound
 * A Branding Object and children
 * @export
 */
export type BrandingRequestCompound = BrandingRequest;


/**
 * @export 
 * A BrandingRequestCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectBrandingRequestCompound
 */
export class DefaultObjectBrandingRequestCompound extends DefaultObject {
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


