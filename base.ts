/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.14
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { Configuration } from "./configuration";
// Some imports not used depending on template conditions
// @ts-ignore
import globalAxios, { AxiosPromise, AxiosInstance, AxiosRequestConfig } from 'axios';

export const BASE_PATH = "https://prod.api.appcluster01.ca-central-1.ezmax.com/rest".replace(/\/+$/, "");

/**
 *
 * @export
 */
export const COLLECTION_FORMATS = {
    csv: ",",
    ssv: " ",
    tsv: "\t",
    pipes: "|",
};

/**
 *
 * @export
 * @interface RequestArgs
 */
export interface RequestArgs {
    url: string;
    options: AxiosRequestConfig;
}

/**
 *
 * @export
 * @class BaseAPI
 */
export class BaseAPI {
    protected configuration: Configuration | undefined;

    constructor(configuration?: Configuration, protected basePath: string = BASE_PATH, protected axios: AxiosInstance = globalAxios) {
        if (configuration) {
            this.configuration = configuration;
            this.basePath = configuration.basePath || this.basePath;
            this.configuration.basePath = this.basePath;
        }
    }
};

/**
 *
 * @export
 * @class RequiredError
 * @extends {Error}
 */
export class RequiredError extends Error {
    name: "RequiredError" = "RequiredError";
    constructor(public field: string, msg?: string) {
        super(msg);
    }
}

export class DefaultObject {
   protected configuration?: Configuration
   protected default: any = {}

   constructor(configuration?: Configuration) {
      if (configuration) this.configuration = configuration
   }

   reset() {
      for (const key in this) {
         if (key != 'default' && typeof this[key] !== 'function') {
            if (key in this.default) {
               this[key] = this.default[key]
            }
         }
      }
      this.build()
   }

   assign(obj: any) {
      this.reset()
      Object.assign(this, obj)
      this.build()
   }

   setDefault() {
      const base = { ...this }
      delete base.default
      this.default = base
   }

   merge(obj: any) {
      Object.assign(this, obj)
      this.build()
   }

   build() {}

   setConfig(configuration: Configuration) {
      this.configuration = configuration
   }

   addProperties(element: any[] | any, props: any) {
      if (element) {
         if (Array.isArray(element)) {
            Object.assign(
               element,
               element.map((el) => {
                  return {
                     ...el,
                     ...props
                  }
               })
            )
         } else {
            Object.assign(element, { ...element, ...props })
         }
      }
   }
}
