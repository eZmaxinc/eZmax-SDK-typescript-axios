/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * 
 * @export
 * @interface ScimAuthenticationScheme
 */
export interface ScimAuthenticationScheme {
    /**
     * A description of the authentication scheme.
     * @type {string}
     * @memberof ScimAuthenticationScheme
     */
    'description': string;
    /**
     * The common authentication scheme name
     * @type {string}
     * @memberof ScimAuthenticationScheme
     */
    'name': string;
    /**
     * The authentication scheme.
     * @type {string}
     * @memberof ScimAuthenticationScheme
     */
    'type': ScimAuthenticationSchemeTypeEnum;
}

export const ScimAuthenticationSchemeTypeEnum = {
    oauth: 'oauth',
    oauth2: 'oauth2',
    oauthbearertoken: 'oauthbearertoken',
    httpbasic: 'httpbasic',
    httpdigest: 'httpdigest'
} as const;
export type ScimAuthenticationSchemeTypeEnum = typeof ScimAuthenticationSchemeTypeEnum[keyof typeof ScimAuthenticationSchemeTypeEnum];


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A ScimAuthenticationScheme Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectScimAuthenticationScheme
 */
export class DataObjectScimAuthenticationScheme {
   description:string = ''
   name:string = ''
   type:ScimAuthenticationSchemeTypeEnum = 'oauth'
}

/**
 * @export 
 * A ScimAuthenticationScheme Validation Object
 * @class ValidationObjectScimAuthenticationScheme
 */
export class ValidationObjectScimAuthenticationScheme {
   description = {
      type: 'string',
      required: true
   }
   name = {
      type: 'string',
      required: true
   }
   type = {
      type: 'enum',
      allowableValues: ['oauth','oauth2','oauthbearertoken','httpbasic','httpdigest'],
      required: true
   }
} 


